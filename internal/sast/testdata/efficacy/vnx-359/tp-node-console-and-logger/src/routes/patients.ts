import { Router } from 'express';
import logger from '../logger';

const router = Router();

router.post('/patients', async (req, res) => {
  const { name, dateOfBirth, ssn } = req.body;
~>  console.log(`new patient ${name} born ${dateOfBirth}`);
~>  logger.info('patient created', { ssn, name });
~>  req.log.debug({ passportNumber: req.body.passportNumber }, 'kyc');
~>  console.error('insert failed for', req.body.socialSecurityNumber);
  res.status(201).end();
});

export default router;
