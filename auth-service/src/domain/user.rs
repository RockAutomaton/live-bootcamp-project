// The User struct should contain 3 fields. email, which is a String; 
// password, which is also a String; and requires_2fa, which is a boolean. 

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub email: String,
    pub password: String,
    pub requires_2fa: bool
}

impl User {
    fn new(email: String, password: String, requires_2fa: bool) -> User {
        User {
            email: email,
            password: password,
            requires_2fa: requires_2fa
        }
    }
}