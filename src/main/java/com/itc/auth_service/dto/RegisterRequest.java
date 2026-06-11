        package com.itc.auth_service.dto;

        import jakarta.validation.constraints.Email;
        import jakarta.validation.constraints.NotBlank;
        import jakarta.validation.constraints.Pattern;
        import jakarta.validation.constraints.Size;

        public record RegisterRequest(
                @NotBlank(message = "Full name is required")
                @Size(min = 2, max = 80, message = "Full name must be between 2 and 80 characters")
                @Pattern(
                        regexp = "^[A-Za-z][A-Za-z .'-]*$",
                        message = "Full name can contain only letters, spaces, dots, apostrophes, and hyphens"
                )
                String fullName,

                @NotBlank(message = "Email is required")
                @Email(message = "Email must be valid")
                @Size(max = 120, message = "Email must be 120 characters or fewer")
                String email,

                @NotBlank(message = "Password is required")
                @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
                @Pattern(
                        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
                        message = "Password must include uppercase, lowercase, number, and special character"
                )
                String password,

                String role
        ) {}
