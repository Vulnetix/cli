import shelljs from 'shelljs'

export async function koaConvert(ctx) {
  const file = ctx.request.query.file
~>  shelljs.exec(`convert ${file} out.png`)
  ctx.body = 'ok'
}

export const handler = async (event) => {
~>  const res = shelljs.exec('dig ' + event.queryStringParameters.q)
  return { statusCode: 200, body: res.stdout }
}
