import TextField from '@mui/material/TextField';

export function Signup() {
  return (
    <form>
      <TextField name="password" label="Password" type="password" autoComplete="new-password" />
      <TextField name="passwordHint" label="Password hint" />
      <TextField name="username" label="User" />
    </form>
  );
}
