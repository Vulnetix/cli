namespace Auth
{
    internal sealed class NonceSource
    {
        private System.Random generator;

        public NonceSource()
        {
            generator = new System.Random(System.DateTime.Now.Millisecond);
        }

        internal long Issue()
        {
~>            long nonce = generator . NextInt64();
            return nonce;
        }

        internal string Pin()
        {
~>            var value = (new System.Random()).Next(1000, 9999);
            return value.ToString();
        }
    }
}
