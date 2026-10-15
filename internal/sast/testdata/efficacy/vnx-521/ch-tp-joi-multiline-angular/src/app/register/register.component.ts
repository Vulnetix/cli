import { FormControl, Validators } from "@angular/forms";

export class RegisterComponent {
  public emailControl = new FormControl("", [Validators.required, Validators.email]);
~>  public passwordControl = new FormControl("", [Validators.required, Validators.minLength(5), Validators.maxLength(40)]);
}
