namespace Shop.Services
{
    public class FormService
    {
        public bool ValidateInput(bool strict) => strict;

        public void Submit(string body)
        {
            if (!ValidateInput(false))
            {
                return;
            }
            var ok = this.ValidateInput(false);
        }
    }
}
