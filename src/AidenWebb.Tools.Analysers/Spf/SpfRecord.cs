using System.Text;

namespace AidenWebb.Tools.Analysers.Spf;

/// <summary>
	///   <para>Parsed instance of the textual representation of a SPF record</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc4408.html">RFC 4408</a>.
	///   </para>
	/// </summary>
	public class SpfRecord : SpfRecordBase
	{
		/// <summary>
		///   Creates a new instance of the SpfRecord
		/// </summary>
		/// <param name="terms">Modifiers and mechanisms of a record</param>
		public SpfRecord(List<SpfTerm> terms)
			: base(terms) { }
		
		
	}