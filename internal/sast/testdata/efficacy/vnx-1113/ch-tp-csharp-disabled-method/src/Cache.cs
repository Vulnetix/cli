namespace App
{
    public class Cache
    {
        /*
        public void Evict()
        {
~>            /* evict oldest first */
            store.RemoveOldest();
        }
        */
        public int Count => store.Count;
    }
}
