using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Game
{
    public class Dealer
    {
        private static readonly Random Rng = new Random(42);
        private readonly Random _jitter = new();

        public void Shuffle(List<Card> deck)
        {
            for (int i = deck.Count - 1; i > 0; i--)
            {
                int j = Rng.Next(i + 1);
                (deck[i], deck[j]) = (deck[j], deck[i]);
            }
        }

        public async Task RetryAsync(Func<Task> action)
        {
            int delay = _jitter.Next(100, 500);
            await Task.Delay(delay);
            await action();
        }

        public string RandomColor()
        {
            var bytes = new byte[3];
            Random.Shared.NextBytes(bytes);
            return "#" + Convert.ToHexString(bytes);
        }

        public double SampleRate()
        {
            return new Random().NextDouble() * 0.1;
        }
    }
}
