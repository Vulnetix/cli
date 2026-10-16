using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Game
{
    public class DeckService
    {
        private readonly Random _rng = new Random();

        public void Shuffle<T>(IList<T> cards)
        {
            for (var i = cards.Count - 1; i > 0; i--)
            {
                var j = _rng.Next(i + 1);
                (cards[i], cards[j]) = (cards[j], cards[i]);
            }
        }

        public async Task RetryAsync(Func<Task> action)
        {
            for (var attempt = 1; attempt <= 5; attempt++)
            {
                try { await action(); return; }
                catch (TimeoutException)
                {
                    var jitterMs = Random.Shared.Next(50, 250) * attempt;
                    await Task.Delay(jitterMs);
                }
            }
        }

        public string RandomColour()
        {
            var hue = _rng.NextDouble() * 360.0;
            return $"hsl({hue:F0}, 70%, 50%)";
        }

        public bool SampleForTelemetry() => Random.Shared.NextDouble() < 0.05;
    }
}
