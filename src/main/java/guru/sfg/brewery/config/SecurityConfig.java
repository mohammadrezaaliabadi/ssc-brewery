package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder getPasswordEncoder(){
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorize -> {
                    authorize.antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find","/beers*").permitAll()
                            .antMatchers(HttpMethod.GET,"/api/v1/beer/**").permitAll()
                            .antMatchers(HttpMethod.GET,"/api/v1/beerUpc/{upc}").permitAll();
                })
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{bcrypt}$2a$10$gRANvjUQSVOWw9TWmINT7.j82d.dfK7M02BmPcSHc4ib4urIaNo5i")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{sha256}1296cefceb47413d3fb91ac7586a4625c33937b4d3109f5a4dd96c79c46193a029db713b96006ded")
                .roles("USER");

        auth.inMemoryAuthentication().withUser("scott").password("{ldap}{SSHA}ZyHC5aYD17+LkLrgpDYyjYJb3ZtBRCRvsGjWwA==").roles("CUSTOMER");
    }

//    @Bean
//    protected UserDetailsService userDetailsService(){
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("admin")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(admin,user);
//    }
}
