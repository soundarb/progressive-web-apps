import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SecurityConfigTest {

    @InjectMocks
    private SecurityConfig securityConfig; // Your class that contains filterChain()

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private HttpSecurity.AuthorizeHttpRequestsConfigurer authorizeHttpRequestsConfigurer;

    @Mock
    private ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry urlRegistry;

    @Mock
    private OAuth2ResourceServerConfigurer<HttpSecurity> resourceServerConfigurer;

    @Mock
    private OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer;

    @Before
    public void setup() throws Exception {
        // Stubbing the chain of calls
        when(httpSecurity.csrf()).thenReturn(httpSecurity);
        when(httpSecurity.disable()).thenReturn(httpSecurity);

        when(httpSecurity.authorizeRequests()).thenReturn(urlRegistry);
        when(urlRegistry.requestMatchers(any(String[].class))).thenReturn(urlRegistry);
        when(urlRegistry.permitAll()).thenReturn(urlRegistry);
        when(urlRegistry.anyRequest()).thenReturn(urlRegistry);
        when(urlRegistry.authenticated()).thenReturn(urlRegistry);

        when(httpSecurity.oauth2ResourceServer()).thenReturn(resourceServerConfigurer);
        when(resourceServerConfigurer.jwt()).thenReturn(jwtConfigurer);

        when(httpSecurity.build()).thenReturn(mock(SecurityFilterChain.class));
    }

    @Test
    public void testFilterChain_withAntMatchersFromDatabase() throws Exception {
        // Optionally, you can spy and override the method if it’s private or needs control
        SecurityConfig configSpy = Mockito.spy(securityConfig);
        List<String> testMatchers = Arrays.asList("/public/**", "/health");

        doReturn(testMatchers).when(configSpy).getAntMatchersFromDatabase();

        SecurityFilterChain result = configSpy.filterChain(httpSecurity);

        verify(httpSecurity).csrf();
        verify(httpSecurity).authorizeRequests();
        verify(urlRegistry).requestMatchers(new String[]{"/public/**", "/health"});
        verify(urlRegistry).permitAll();
        verify(urlRegistry).anyRequest();
        verify(urlRegistry).authenticated();
        verify(httpSecurity).oauth2ResourceServer();
        verify(resourceServerConfigurer).jwt();
        verify(httpSecurity).build();
    }
}
