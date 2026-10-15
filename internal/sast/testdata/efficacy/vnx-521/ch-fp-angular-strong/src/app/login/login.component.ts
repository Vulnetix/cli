import { FormControl, Validators } from "@angular/forms";

export class LoginComponent {
  public usernameControl = new FormControl("", [Validators.required, Validators.minLength(3)]);
  public passwordControl = new FormControl("", [Validators.required, Validators.minLength(12)]);
  public pinControl = new FormControl("", [Validators.minLength(4)]);
}
