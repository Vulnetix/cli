describe('captcha', () => {
  it('fixture', () => {
    const captchaCode = Math.random().toString(36).slice(2, 8);
    const res = { json: () => {} };
    expect(captchaCode).toBeTruthy();
  });
});
