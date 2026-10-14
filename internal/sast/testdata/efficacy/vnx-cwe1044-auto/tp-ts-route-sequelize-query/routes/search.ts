import { type Request, type Response, type NextFunction } from 'express'
import * as models from '../models/index'

export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    const criteria: string = req.query.q === 'undefined' ? '' : String(req.query.q ?? '')
~>    models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)
      .then(([products]: any) => res.json(products))
      .catch((error: Error) => next(error))
  }
}
