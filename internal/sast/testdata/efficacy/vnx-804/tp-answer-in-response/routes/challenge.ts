import { type Request, type Response } from 'express'
import { CaptchaModel } from '../models/captcha'

export function newCaptcha () {
  return async (req: Request, res: Response) => {
    const expression = buildExpression()
    const answer = solve(expression)
    const captcha = {
      captchaId: nextId(),
      captcha: expression,
      answer
    }
    await CaptchaModel.build(captcha).save()
~>    res.json(captcha)
  }
}
