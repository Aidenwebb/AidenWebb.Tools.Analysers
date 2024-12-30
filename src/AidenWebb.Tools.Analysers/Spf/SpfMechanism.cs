using System.Text;

namespace AidenWebb.Tools.Analysers.Spf;

/// <summary>
	///   Represents a single mechanism term in a SPF record
	/// </summary>
	public class SpfMechanism : SpfTerm
	{
		/// <summary>
		///   Qualifier of the mechanism
		/// </summary>
		public SpfQualifier Qualifier { get; }

		/// <summary>
		///   Type of the mechanism
		/// </summary>
		public SpfMechanismType Type { get; }

		/// <summary>
		///   The Host part of the mechanism
		/// </summary>
		public string? Host { get; }

		/// <summary>
		///   IPv4 prefix of the mechanism
		/// </summary>
		public int? Prefix { get; }

		/// <summary>
		///   IPv6 prefix of the mechanism
		/// </summary>
		public int? Prefix6 { get; }

		/// <summary>
		///   Creates a new instance of the SpfMechanism
		/// </summary>
		/// <param name="qualifier">Qualifier of the mechanism</param>
		/// <param name="type">Type of the mechanism</param>
		/// <param name="host">Domain part of the mechanism</param>
		/// <param name="prefix">IPv4 prefix of the mechanism</param>
		/// <param name="prefix6">IPv6 prefix of the mechanism</param>
		public SpfMechanism(SpfQualifier qualifier, SpfMechanismType type, string? host = null, int? prefix = null, int? prefix6 = null)
		{
			Qualifier = qualifier;
			Type = type;
			Host = host;
			Prefix = prefix;
			Prefix6 = prefix6;
		}

		/// <summary>
		///   Returns the textual representation of a mechanism term
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			var res = new StringBuilder
			{
				Capacity = 0,
				Length = 0
			};

			switch (Qualifier)
			{
				case SpfQualifier.Fail:
					res.Append("-");
					break;
				case SpfQualifier.SoftFail:
					res.Append("~");
					break;
				case SpfQualifier.Neutral:
					res.Append("?");
					break;
			}

			res.Append(EnumHelper<SpfMechanismType>.ToString(Type).ToLowerInvariant());

			if (!String.IsNullOrEmpty(Host))
			{
				res.Append(":");
				res.Append(Host);
			}

			if (Prefix.HasValue)
			{
				res.Append("/");
				res.Append(Prefix.Value);
			}

			if (Prefix6.HasValue)
			{
				res.Append("//");
				res.Append(Prefix6.Value);
			}

			return res.ToString();
		}
	}