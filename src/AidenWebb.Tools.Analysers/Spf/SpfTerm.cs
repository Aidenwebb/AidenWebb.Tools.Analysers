using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace AidenWebb.Tools.Analysers.Spf;

	/// <summary>
	///   Represents a single term of a SPF record
	/// </summary>
	public abstract class SpfTerm
	{
		private static readonly Regex _parseMechanismRegex = new Regex(@"^(\s)*(?<qualifier>[~+?-]?)(?<type>[a-z0-9]+)(:(?<domain>[^/]+))?(/(?<prefix>[0-9]+)(/(?<prefix6>[0-9]+))?)?(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
		private static readonly Regex _parseModifierRegex = new Regex(@"^(\s)*(?<type>[a-z]+)=(?<domain>[^\s]+)(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

		internal static bool TryParse(string s, out SpfTerm? value)
		{
			if (String.IsNullOrEmpty(s))
			{
				value = null;
				return false;
			}

			#region Parse Mechanism
			Match match = _parseMechanismRegex.Match(s);
			if (match.Success)
			{
				SpfQualifier qualifier;
				switch (match.Groups["qualifier"].Value)
				{
					case "+":
						qualifier = SpfQualifier.Pass;
						break;
					case "-":
						qualifier = SpfQualifier.Fail;
						break;
					case "~":
						qualifier = SpfQualifier.SoftFail;
						break;
					case "?":
						qualifier = SpfQualifier.Neutral;
						break;

					default:
						qualifier = SpfQualifier.Pass;
						break;
				}

				SpfMechanismType type = EnumHelper<SpfMechanismType>.TryParse(match.Groups["type"].Value, true, out SpfMechanismType t) ? t : SpfMechanismType.Unknown;
				string? domain = match.Groups["domain"].Value;

				string tmpPrefix = match.Groups["prefix"].Value;
				int? prefix = null;
				if (!String.IsNullOrEmpty(tmpPrefix) && Int32.TryParse(tmpPrefix, out int p))
				{
					prefix = p;
				}

				tmpPrefix = match.Groups["prefix6"].Value;
				int? prefix6 = null;
				if (!String.IsNullOrEmpty(tmpPrefix) && Int32.TryParse(tmpPrefix, out int p6))
				{
					prefix6 = p6;
				}

				value = new SpfMechanism(qualifier, type, domain, prefix, prefix6);
				return true;
			}
			#endregion

			#region Parse Modifier
			match = _parseModifierRegex.Match(s);
			if (match.Success)
			{
				value = new SpfModifier(
					EnumHelper<SpfModifierType>.TryParse(match.Groups["type"].Value, true, out SpfModifierType t) ? t : SpfModifierType.Unknown,
					match.Groups["domain"].Value);
				return true;
			}
			#endregion

			value = null;
			return false;
		}
	}