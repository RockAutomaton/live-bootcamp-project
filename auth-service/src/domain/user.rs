// The User struct should contain 3 fields. email, which is a String; 
// password, which is also a String; and requires_2fa, which is a boolean. 

use super::{Email, Password};

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> User {
        User {
            email: email,
            password: password,
            requires_2fa: requires_2fa
        }
    }
}