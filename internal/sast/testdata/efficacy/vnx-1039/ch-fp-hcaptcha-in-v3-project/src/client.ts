declare const grecaptcha: any;
export const getToken = () => grecaptcha.execute(process.env.SITE_KEY, { action: 'comment' });
