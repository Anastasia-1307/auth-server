export interface ValidationError {
  field: string;
  message: string;
}

export function validateEmail(email: string): ValidationError | null {
  if (!email || !email.includes("@")) {
    return { field: "email", message: "Email invalid" };
  }
  return null;
}

export function validatePassword(password: string): ValidationError | null {
  if (!password || password.length < 8) {
    return { field: "password", message: "Parola trebuie să aibă minim 8 caractere" };
  }
  return null;
}

export function validateUsername(username: string): ValidationError | null {
  if (!username || username.length < 3) {
    return { field: "username", message: "Nume prea scurt" };
  }
  return null;
}

export function validateRegistration(data: {
  email: string;
  password: string;
  username?: string;
}): ValidationError[] {
  const errors: ValidationError[] = [];
  
  const emailError = validateEmail(data.email);
  if (emailError) errors.push(emailError);
  
  const passwordError = validatePassword(data.password);
  if (passwordError) errors.push(passwordError);
  
  if (data.username) {
    const usernameError = validateUsername(data.username);
    if (usernameError) errors.push(usernameError);
  }
  
  return errors;
}
