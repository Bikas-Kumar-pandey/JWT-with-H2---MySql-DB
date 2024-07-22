* How it knows that i have given right credentials or not?

1. whenever App starts it will run SecurityConfig and where it has authenticationProvider bean that it will
   provider.setUserDetailsService(userDetailsService); set userDetailsService (MyUserDetailsService)
2. MyUserDetailsService implements UserDetailsService and we have overriden the loadUserByUsername which will fetch
   details from DB
3. authenticationManager.authenticate(usernamePasswordAuthenticationToken); has inbuilt functions to validate creds.


