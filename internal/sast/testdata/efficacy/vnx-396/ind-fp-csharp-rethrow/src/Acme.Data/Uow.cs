using System;
using Microsoft.Extensions.Logging;

namespace Acme.Data
{
    public class Uow
    {
        private readonly ITransaction _tx;
        private readonly ILogger<Uow> _logger;

        public Uow(ITransaction tx, ILogger<Uow> logger)
        {
            _tx = tx;
            _logger = logger;
        }

        public void Commit()
        {
            try
            {
                _tx.Commit();
            }
            catch (Exception)
            {
                _tx.Rollback();
                throw;
            }
        }

        public bool TryCommit()
        {
            try
            {
                _tx.Commit();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "commit failed");
                return false;
            }
        }
    }
}
