﻿namespace AidenWebb.Tools.Analysers;

internal static class EnumHelper<T>
    where T : struct, Enum
{
    private static readonly Dictionary<T, string> _names;
    private static readonly Dictionary<string, T> _values;

    static EnumHelper()
    {
        string[] names = Enum.GetNames(typeof(T));
        T[] values = (T[]) Enum.GetValues(typeof(T));

        _names = new Dictionary<T, string>(names.Length);
        _values = new Dictionary<string, T>(names.Length * 2);

        for (int i = 0; i < names.Length; i++)
        {
            _names[values[i]] = names[i];
            _values[names[i]] = values[i];
            _values[names[i].ToLowerInvariant()] = values[i];
        }
    }

    public static bool TryParse(string s, bool ignoreCase, out T value)
    {
        if (String.IsNullOrEmpty(s))
        {
            value = default;
            return false;
        }

        return _values.TryGetValue((ignoreCase ? s.ToLowerInvariant() : s), out value);
    }

    public static string ToString(T value)
    {
        return _names.TryGetValue(value, out var res) ? res : Convert.ToInt64(value).ToString();
    }

    public static Dictionary<T, string> Names => _names;

    internal static T Parse(string s, bool ignoreCase, T defaultValue)
    {
        return TryParse(s, ignoreCase, out var res) ? res : defaultValue;
    }

    internal static T Parse(string s, bool ignoreCase)
    {
        if (TryParse(s, ignoreCase, out var res))
            return res;

        throw new ArgumentOutOfRangeException(nameof(s));
    }
}

internal static class EnumHelper
{
    public static bool IsAnyOf<T>(this T value, params T[] valuesToCheck)
        where T : struct, Enum
    {
        return valuesToCheck.Any(x => value.Equals(x));
    }
}