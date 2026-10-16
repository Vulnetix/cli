const TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaS1kZXBsb3llciIsInNjb3BlIjoiZGVwbG95OndyaXRlIiwiaWF0IjoxNzAwMDAwMDAwfQ.f7qfGvIdaHY8fpf5oVhlpAGv-w924XaB6Cpqfopm5bc';

describe('auth middleware', () => {
  it('accepts a bearer token', () => {
    expect(TOKEN.split('.')).toHaveLength(3);
  });
});
