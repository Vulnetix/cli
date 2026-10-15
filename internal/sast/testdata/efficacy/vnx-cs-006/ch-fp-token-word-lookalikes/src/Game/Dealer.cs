namespace App.Game;

public class Dealer
{
    private readonly Random _rng = new Random(42);

    public int DrawTokenCount() => _rng.Next(1, 6);

    public string PickColour(string[] colours)
    {
        var keyIndex = _rng.Next(colours.Length);
        return colours[keyIndex];
    }

    public Card Deal(Deck deck) => deck.Cards[_rng.Next(deck.Cards.Count)];
}
