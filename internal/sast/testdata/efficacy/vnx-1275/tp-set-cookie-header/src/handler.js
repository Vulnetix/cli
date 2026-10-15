exports.handler = async (event) => {
  const sid = createSession(event);
  return {
    statusCode: 200,
    headers: {
~>      'Set-Cookie': `sid=${sid}; Path=/; Secure; HttpOnly; SameSite=None`,
    },
  };
};

function legacy(res, sid) {
~>  res.setHeader('Set-Cookie', 'sid=' + sid + '; HttpOnly; SameSite=None');
}
