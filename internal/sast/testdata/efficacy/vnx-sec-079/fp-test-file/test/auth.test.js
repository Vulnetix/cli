test('detects', () => expect(isToken('github_pat_@@sample:[A-Za-z0-9]{22}@@_@@sample:[A-Za-z0-9]{59}@@')).toBe(true));
