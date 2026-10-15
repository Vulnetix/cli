import TextField from '@mui/material/TextField';

export default function Login() {
  return (
    <form>
      <TextField name="email" label="Email" type="email" />
~>      <TextField
        name="password"
        label="Password"
        variant="outlined"
      />
    </form>
  );
}
