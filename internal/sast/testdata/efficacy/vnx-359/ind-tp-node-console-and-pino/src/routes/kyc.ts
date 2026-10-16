import { Router } from 'express';
import pino from 'pino';

const logger = pino();
export const router = Router();

router.post('/kyc', async (req, res) => {
  const body = req.body;
~>  console.log(`KYC payload received ssn=${body.ssn} for ${body.email}`);
  const user = await saveProfile(body);
~>  logger.info({ userId: user.id, dateOfBirth: user.dateOfBirth }, 'profile updated');
  res.status(201).json({ id: user.id });
});

router.get('/lookup', async (req, res) => {
  const { ssn } = req.query;
~>  req.log.debug({ ssn }, 'lookup by identifier');
  res.json(await findByIdentifier(ssn));
});
