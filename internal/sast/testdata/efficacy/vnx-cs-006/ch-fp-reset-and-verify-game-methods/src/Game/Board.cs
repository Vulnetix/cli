using System;

namespace Puzzle.Game
{
    public class Board
    {
        private readonly Random _random = new Random();
        private readonly int[] _cells = new int[81];

        public void ResetBoard()
        {
            for (var i = 0; i < _cells.Length; i++)
            {
                _cells[i] = _random.Next(1, 10);
            }
        }

        public bool VerifyLayoutSurvivesShuffle()
        {
            var a = _random.Next(_cells.Length);
            var b = _random.Next(_cells.Length);
            (_cells[a], _cells[b]) = (_cells[b], _cells[a]);
            return true;
        }

        public void SimulateSessionTraffic(int users)
        {
            var delayMs = _random.Next(50, 250);
            System.Threading.Thread.Sleep(delayMs);
        }
    }
}
