import { CognitoIdentityProviderClient, AdminAddUserToGroupCommand } from '@aws-sdk/client-cognito-identity-provider';
import { Request, Response } from 'express';

const cognito = new CognitoIdentityProviderClient({});

export async function onboard(req: Request, res: Response): Promise<void> {
  await cognito.send(new AdminAddUserToGroupCommand({
    UserPoolId: process.env.POOL_ID,
    Username: req.body.username,
~>    GroupName: req.body.team,
  }));
  res.sendStatus(204);
}

export async function addMember(req: Request, res: Response): Promise<void> {
~>  await directory.addUserToGroup(req.user.id, req.query.group as string);
  res.sendStatus(204);
}
