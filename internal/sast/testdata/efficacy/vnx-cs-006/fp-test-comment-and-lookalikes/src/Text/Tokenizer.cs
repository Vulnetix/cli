using System;

namespace Text
{
    public class Tokenizer
    {
        private readonly Lexer _lexer;

        // Never use new Random().Next() to build a session token or password.
        /* Random.Shared.NextBytes(key) is not a key generator. */
        public Token NextToken()
        {
            var token = _lexer.Next();
            Log.Warn("rng.Next() must not be used for password reset tokens");
            return token;
        }

        public string RandomSessionHint()
        {
            return "use RandomNumberGenerator for the session key";
        }
    }
}
