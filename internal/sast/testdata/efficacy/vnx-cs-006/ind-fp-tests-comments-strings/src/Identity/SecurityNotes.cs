namespace Identity
{
    public static class SecurityNotes
    {
        // Never generate a password token with new Random().Next(); use RandomNumberGenerator.
        public const string Guidance = "Do not use new Random().Next() for a password reset token";
    }
}
