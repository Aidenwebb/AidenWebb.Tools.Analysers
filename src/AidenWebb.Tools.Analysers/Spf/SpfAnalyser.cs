using DnsClient;
using DnsClient.Protocol;

namespace AidenWebb.Tools.Analysers.Spf;

public class SpfAnalyser
{
    public async Task<SpfAnalyserResult> AnalyseAsync(SpfRecord record)
    {
        var result = new SpfAnalyserResult
        {
            RecordText = record.ToString(),
            SpfRecord = record,
            Errors = new List<SpfErrorDetail>()
        };

        // 1. Validate SPF record structure
        ValidateStructure(record, result.Errors);

        // 2. Recursively count DNS lookups
        result.DnsLookupCount = await CountDnsLookupsAsync(record, result.Errors);
        
        // 3. Recursively count void lookups
        result.VoidLookupCount = await CountVoidLookupsAsync(record, result.Errors);
        
        // Check if any errors are fatal
        result.RecordIsValid = !result.Errors.Any(e => e.Severity == SpfErrorSeverity.Error);

        // FailureMode based on ALL Mechanism
        result.MechanismFailureMode = DetermineFailureMode(record);

        return await Task.FromResult(result);
    }

    private void ValidateStructure(SpfRecord record, List<SpfErrorDetail> errors)
    {
        // e.g. Check if record starts with "v=spf1"
        if (!SpfRecordBase.IsSpfRecord(record.ToString()))
        {
            errors.Add(new SpfErrorDetail
            {
                Code = "E100",
                Message = "SPF record does not start with 'v=spf1'.",
                Severity = SpfErrorSeverity.Error
            });
        }

        // etc...
    }
    
    private SpfQualifier DetermineFailureMode(SpfRecord record)
    {
        // 1) Find the 'ALL' mechanism in the record’s terms
        var allMechanism = record.Terms
            .OfType<SpfMechanism>()
            .FirstOrDefault(m => m.Type == SpfMechanismType.All);

        if (allMechanism == null)
        {
            // If there's no 'all' mechanism at all, many implementations treat it as if it's "all ?all"
            // meaning "Neutral" for non-matching senders. 
            // However, your policy may prefer 'None' or 'Neutral' in this scenario.
            return SpfQualifier.Pass;
        }

        // 2) Return the qualifier that was parsed for the ALL mechanism
        //    The qualifier might be Pass (+), Fail (-), SoftFail (~), Neutral (?), or None
        return allMechanism.Qualifier;
    }

    
     /// <summary>
    /// Recursively counts the total number of DNS lookups caused by this SPF record.
    /// Includes 'A', 'MX', 'PTR', 'Exists', 'Include' mechanisms, and the 'Redirect' modifier.
    /// </summary>
    /// <param name="record">The SPF record to analyze.</param>
    /// <param name="errors">List of errors to populate if something goes wrong.</param>
    /// <param name="visitedDomains">
    /// A set of domains we have already visited. Used to avoid infinite loops in nested includes/redirects.
    /// </param>
    /// <returns>The total number of DNS lookups required by <paramref name="record"/>.</returns>
    public async Task<int> CountDnsLookupsAsync(
        SpfRecord record, 
        List<SpfErrorDetail> errors, 
        HashSet<string>? visitedDomains = null)
    {
        visitedDomains ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // For illustration, let's treat the record's "domain" as 
        // any domain found in the directive that led us here.
        // If you store a domain property in SpfRecord, use that instead.
        // Or pass the domain as a separate parameter.

        // 1) Count the DNS lookups from local terms
        int localLookupCount = 0;

        foreach (SpfTerm term in record.Terms)
        {
            // Is it a mechanism that triggers a DNS lookup?
            if (term is SpfMechanism mechanism)
            {
                switch (mechanism.Type)
                {
                    case SpfMechanismType.A:
                    case SpfMechanismType.Mx:
                    case SpfMechanismType.Ptr:
                    case SpfMechanismType.Exists:
                        // Each of these typically requires 1 DNS lookup.
                        localLookupCount++;

                        // If the mechanism references another domain (e.g., "a:example.com"),
                        // you might do a DNS query or further checks here if needed.
                        break;

                    case SpfMechanismType.Include:
                        localLookupCount++;
                        // "include" references another domain: mechanism.Domain
                        // Recursively process that domain's SPF record if we haven't already.
                        if (!string.IsNullOrWhiteSpace(mechanism.Host))
                        {
                            localLookupCount += await ProcessNestedSpfAsync(
                                mechanism.Host, 
                                visitedDomains, 
                                errors);
                        }
                        break;

                    default:
                        // Other mechanisms either don't require DNS or are unknown.
                        break;
                }
            }
            else if (term is SpfModifier modifier && modifier.Type == SpfModifierType.Redirect)
            {
                // "redirect=example.com" also triggers a DNS lookup
                localLookupCount++;

                // Then recursively process that domain's SPF record
                if (!string.IsNullOrWhiteSpace(modifier.Host))
                {
                    localLookupCount += await ProcessNestedSpfAsync(
                        modifier.Host, 
                        visitedDomains, 
                        errors);
                }
            }
        }

        return localLookupCount;
    }

    /// <summary>
    /// Retrieves and parses the SPF record for <paramref name="domain"/>,
    /// then counts its DNS lookups recursively.
    /// </summary>
    private async Task<int> ProcessNestedSpfAsync(
        string domain, 
        HashSet<string> visitedDomains,
        List<SpfErrorDetail> errors)
    {
        int nestedCount = 0;

        // If we have already visited this domain, skip to avoid infinite loop
        if (visitedDomains.Contains(domain))
        {
            return 0;
        }

        visitedDomains.Add(domain);

        // 1) Fetch SPF record text from DNS for that domain
        string? spfText;
        try
        {
            spfText = await FetchSpfRecordTextAsync(domain, errors);
        }
        catch (Exception ex)
        {
            errors.Add(new SpfErrorDetail
            {
                Code = "DNS_LOOKUP_FAILED",
                Message = $"Failed to fetch SPF record for '{domain}'. {ex.Message}",
                TermValue = domain,
                Severity = SpfErrorSeverity.Error
            });
            return 0;
        }

        // 2) Parse the record if we got something
        if (!string.IsNullOrWhiteSpace(spfText))
        {
            if (SpfRecordBase.TryParse(spfText, out SpfRecord? spfRecord))
            {
                // 3) Now count DNS lookups within that nested record
                nestedCount = await CountDnsLookupsAsync(spfRecord, errors, visitedDomains);
            }
            else
            {
                errors.Add(new SpfErrorDetail
                {
                    Code = "SPF_PARSE_FAILED",
                    Message = $"Failed to parse nested SPF record for '{domain}'.",
                    TermValue = spfText,
                    Severity = SpfErrorSeverity.Error
                });
            }
        }

        return nestedCount;
    }
    
            /// <summary>
        /// Recursively counts the number of "void lookups" in an SPF record.
        /// A "void lookup" is typically defined as a DNS lookup that returns no records (NXDOMAIN or an empty result).
        /// </summary>
        /// <param name="record">The SPF record to analyze.</param>
        /// <param name="errors">List of errors to populate if something goes wrong.</param>
        /// <param name="visitedDomains">
        /// A set of domains we have already visited. Used to avoid infinite loops in nested includes/redirects.
        /// </param>
        /// <returns>The total number of void lookups for this record (including nested references).</returns>
        public async Task<int> CountVoidLookupsAsync(
            SpfRecord record, 
            List<SpfErrorDetail> errors, 
            HashSet<string>? visitedDomains = null)
        {
            visitedDomains ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            int localVoidCount = 0;

            foreach (SpfTerm term in record.Terms)
            {
                if (term is SpfMechanism mechanism)
                {
                    switch (mechanism.Type)
                    {
                        case SpfMechanismType.A:
                        case SpfMechanismType.Mx:
                        case SpfMechanismType.Ptr:
                        case SpfMechanismType.Exists:
                            // Each of these triggers a DNS query for the mechanism's domain (if provided).
                            // If the query returns no records, that's a "void" lookup.
                            if (!string.IsNullOrWhiteSpace(mechanism.Host))
                            {
                                bool isVoid = await IsVoidLookupAsync(mechanism.Host, errors);
                                if (isVoid)
                                {
                                    localVoidCount++;
                                }
                            }
                            break;

                        case SpfMechanismType.Include:
                            // "include" also triggers a DNS query to retrieve the nested SPF record.
                            // If the DNS returns no TXT record or NXDOMAIN, that's a void lookup.
                            if (!string.IsNullOrWhiteSpace(mechanism.Host))
                            {
                                bool isVoid = await IsVoidLookupAsync(mechanism.Host, errors);
                                if (isVoid)
                                {
                                    localVoidCount++;
                                }
                                else
                                {
                                    // If not void, recursively check the nested SPF for further void lookups.
                                    localVoidCount += await ProcessNestedSpfForVoidAsync(
                                        mechanism.Host,
                                        visitedDomains,
                                        errors);
                                }
                            }
                            break;

                        default:
                            // Other mechanisms (ip4, ip6, all, unknown, etc.) do not cause DNS lookups (or do so differently).
                            break;
                    }
                }
                else if (term is SpfModifier modifier && modifier.Type == SpfModifierType.Redirect)
                {
                    // "redirect=example.com" also triggers a DNS query for that domain's SPF.
                    if (!string.IsNullOrWhiteSpace(modifier.Host))
                    {
                        bool isVoid = await IsVoidLookupAsync(modifier.Host, errors);
                        if (isVoid)
                        {
                            localVoidCount++;
                        }
                        else
                        {
                            localVoidCount += await ProcessNestedSpfForVoidAsync(
                                modifier.Host,
                                visitedDomains,
                                errors);
                        }
                    }
                }
            }

            return localVoidCount;
        }
    
    /// <summary>
    /// Checks if a DNS lookup for SPF/TXT records of <paramref name="domain"/> yields no results.
    /// If the domain returns NXDOMAIN or an empty set of TXT records, it's considered "void."
    /// </summary>
    private async Task<bool> IsVoidLookupAsync(string domain, List<SpfErrorDetail> errors)
    {
        try
        {
            var records = await TryFetchDnsRecordsAsync(domain, errors);
            // If we got zero results, that means it's a void lookup.
            return records == null || records.Count == 0;
        }
        catch (Exception ex)
        {
            // Treat an exception as a void or possibly log an error. 
            // Typically NXDOMAIN or any DNS failure is "void" in an SPF context.
            errors.Add(new SpfErrorDetail
            {
                Code = "DNS_LOOKUP_FAILED",
                Message = $"DNS lookup for '{domain}' failed: {ex.Message}",
                TermValue = domain
            });
            return true; // Or false, depending on how you want to treat errors.
        }
    }
    
    /// <summary>
    /// Retrieves and parses the SPF record for <paramref name="domain"/> (if present),
    /// then recursively counts void lookups in that nested record.
    /// </summary>
    private async Task<int> ProcessNestedSpfForVoidAsync(
        string domain,
        HashSet<string> visitedDomains,
        List<SpfErrorDetail> errors)
    {
        if (visitedDomains.Contains(domain))
        {
            // Already visited, avoid infinite loops
            return 0;
        }
        visitedDomains.Add(domain);

        // 1) Fetch the nested SPF text for the domain.
        string? spfText = await FetchSpfRecordTextAsync(domain, errors);
        if (string.IsNullOrWhiteSpace(spfText))
        {
            // No record found => that might count as a "void" scenario if the domain had no SPF at all
            // But we've already counted it in IsVoidLookupAsync above, so typically do nothing here.
            return 0;
        }

        // 2) Parse the record. If parse fails, no additional void lookups can be discovered.
        if (!SpfRecordBase.TryParse(spfText, out SpfRecord? spfRecord))
        {
            errors.Add(new SpfErrorDetail
            {
                Code = "SPF_PARSE_FAILED",
                Message = $"Failed to parse SPF record for domain '{domain}'.",
                TermValue = spfText
            });
            return 0;
        }

        // 3) Recursively count void lookups in the nested record
        return await CountVoidLookupsAsync(spfRecord, errors, visitedDomains);
    }
    
    /// <summary>
    /// Example method to fetch *all* TXT records for a given domain (placeholder).
    /// Returns null if not found or an empty list if none match.
    /// </summary>
    private async Task<List<string>?> TryFetchDnsRecordsAsync(
        string domain,
        List<SpfErrorDetail> errors)
    {
        
        var lookup = new LookupClient();
        var result = await lookup.QueryAsync(domain, QueryType.TXT);

        return result.AllRecords.OfType<TxtRecord>().SelectMany(r => r.Text).Where(line => line.Contains("v=spf1"))
            .ToList();
    }

    /// <summary>
    /// Sample function that fetches the raw SPF record text for a given domain.
    /// This is just a placeholder; you'd need to implement DNS lookups or
    /// call a library that does this for you.
    /// </summary>
    /// <param name="domain">Domain to fetch SPF record for.</param>
    /// <param name="errors">List of errors to capture if something fails.</param>
    /// <returns>The raw SPF record text, or null if not found.</returns>
    private async Task<string?> FetchSpfRecordTextAsync(
        string domain, 
        List<SpfErrorDetail> errors)
    {
        // Placeholder: Perform a TXT record lookup in DNS for the domain.
        // For example, you could use DnsClient.NET or a similar library to retrieve TXT records:
        //
        var lookup = new LookupClient();
        var result = await lookup.QueryAsync(domain, QueryType.TXT);
        foreach (var txt in result.AllRecords.OfType<TxtRecord>())
        {
            string txtVal = string.Join("", txt.Text);
            if (txtVal.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase))
            {
                return txtVal;
            }
        }
        
        return null;

        await Task.Delay(50); // Simulate async I/O

        // For demonstration, pretend we found one:
        // NOTE: In real code, this would do an actual DNS query.
        return $"v=spf1 include:_spf.somewhere.com -all";
    }
    
}