import TextField from '@mui/material/TextField';

export function LoginFields() {
  return (
    <>
      <TextField label="Email" name="email" type="email" fullWidth />
~>      <TextField label="Password" name="password" variant="outlined" fullWidth />
    </>
  );
}
