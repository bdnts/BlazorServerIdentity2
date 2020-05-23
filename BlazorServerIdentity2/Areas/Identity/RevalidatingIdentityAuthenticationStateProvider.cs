using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System.Text;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.WebUtilities;

namespace BlazorServerIdentity2.Areas.Identity
{
    public class RevalidatingIdentityAuthenticationStateProvider<TUser>
        : RevalidatingServerAuthenticationStateProvider where TUser : class
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IdentityOptions _options;
        private ILogger _logger;

        public RevalidatingIdentityAuthenticationStateProvider(
            ILoggerFactory loggerFactory,
            IServiceScopeFactory scopeFactory,
            IOptions<IdentityOptions> optionsAccessor)
            : base(loggerFactory)
        {
            _scopeFactory = scopeFactory;
            _options = optionsAccessor.Value;
            _logger = loggerFactory.CreateLogger("RevalidatingIdentityAuthenticationStateProvider");
        }

        protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

        protected override async Task<bool> ValidateAuthenticationStateAsync(
		    AuthenticationState authenticationState, CancellationToken cancellationToken)
        {
            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                return await ValidateSecurityStampAsync(userManager, authenticationState.User);
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        private async Task<bool> ValidateSecurityStampAsync(UserManager<TUser> userManager, ClaimsPrincipal principal)
        {
            var user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                return false;
            }
            else if (!userManager.SupportsUserSecurityStamp)
            {
                return true;
            }
            else
            {
                var principalStamp = principal.FindFirstValue(_options.ClaimsIdentity.SecurityStampClaimType);
                var userStamp = await userManager.GetSecurityStampAsync(user);
                return principalStamp == userStamp;
            }
        }
        public async Task<bool> CheckPasswordAsync(TUser user, string password)
        {
            
            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var signInResult = await userManager.CheckPasswordAsync(user, password);
                return signInResult;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public async Task<IdentityResult> ConfirmEmailAsync(TUser user,  string token)
        {
            if (user == null) return IdentityResult.Failed(new IdentityError() { Code = "ConfirmEmailAsync 1", Description = "user is null" });
            if (string.IsNullOrEmpty(token)) return IdentityResult.Failed(new IdentityError() { Code = "ConfirmEmailAsync 2", Description = "token is null" });

            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                //var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var luser = await userManager.ConfirmEmailAsync(user, token);
                return IdentityResult.Success;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public async Task<IdentityResult> ConfirmEmailPlusFindFirstAsync(string id, string token)
        {
            if (string.IsNullOrEmpty(id)) return IdentityResult.Failed(new IdentityError() { Code = "ConfirmEmailAsync 1", Description = "user is null" });
            if (string.IsNullOrEmpty(token)) return IdentityResult.Failed(new IdentityError() { Code = "ConfirmEmailAsync 2", Description = "token is null" });

            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManagerx = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var user = await userManagerx.FindByIdAsync(id);
                if (user == null) return null;
                var result = await userManagerx.ConfirmEmailAsync(user, token);
                return result;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public async Task<ClaimsPrincipal> CreateUserPrincipalAsync(TUser user)
        {
            
            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<TUser>>();

                var principal = await signInManager.CreateUserPrincipalAsync(user);
                return principal;
            }
            catch(Exception ex)
            {
                _logger.LogError(ex.Message);
                return null;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public  async Task<IdentityResult> CreateAsync(TUser user, string password)
        {          
            if (user == null) return IdentityResult.Failed(new IdentityError() { Code = "CreateAsync 1", Description = "user is null" });
            if (string.IsNullOrEmpty(password)) return IdentityResult.Failed(new IdentityError() { Code = "CreateAsync 2", Description = "password is null" });

            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var resultCreateUser = await userManager.CreateAsync(user, password);
                return resultCreateUser;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public async Task<TUser> FindByIdAsync(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;

            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var user = await userManager.FindByIdAsync(id);
                return user;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public async Task<TUser> FindByNameAsync(string username)
        {
            if (string.IsNullOrEmpty(username)) return null;

            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var user = await userManager.FindByNameAsync(username);
                return user;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            if (user==null) return null;
            // Get the user manager from a new scope to ensure it fetches fresh data
            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var claims = await userManager.GetClaimsAsync(user);

                return claims;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }


        public async Task<string> GetUrl(TUser user, string id, string baseuri, string path)
        {
            var scope = _scopeFactory.CreateScope();
            try
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TUser>>();
                var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var queryparams = new Dictionary<string, string>()
                {
                    {"userid", id},
                    { "code", code}
                };
                var callbackUrl = QueryHelpers.AddQueryString(baseuri + path, queryparams);
                return callbackUrl;
            }
            catch (NullReferenceException)
            {
                // Something wasn't set yet, just return null
                return null;
            }
            catch (Exception exp)
            {
                Console.WriteLine("Caught Expception {0}", exp.Message);
                throw exp;
            }
            finally
            {
                if (scope is IAsyncDisposable asyncDisposable)
                {
                    await asyncDisposable.DisposeAsync();
                }
                else
                {
                    scope.Dispose();
                }
            }
        }

        public async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {           
            if (string.IsNullOrEmpty(userName)) return SignInResult.Failed;
            if (string.IsNullOrEmpty(password)) return SignInResult.Failed;

            var user = await FindByNameAsync(userName);
            if (user == null) return SignInResult.Failed;

            var claims = await GetClaimsAsync(user);
            if (claims == null) return SignInResult.Failed;

            var principal = await CreateUserPrincipalAsync(user);
            if (principal == null) return SignInResult.Failed;

            // Create new list with claims as principal
            var resultU = claims.Union(principal.Claims, new ClaimComparer());

            //var query = from claim in claims
            //             pclaim in principal.Claims on claim.Type equals pclaim.Type
            //            select new { claim.Type, pclaim.V}
            var identity = new ClaimsIdentity(
                resultU,
                //principal.Claims,
                //*************************
                // This should be explored further to see if there is a better type.
                Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme
            );
            principal = new System.Security.Claims.ClaimsPrincipal(identity);
            //This next statement is the heart at reflecting that the user is signed in.
            this.SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));
            // now the authState is updated
            var authState = await GetAuthenticationStateAsync();
            return SignInResult.Success;
        }

        public async Task<ClaimsPrincipal> Refresh()
        {           
            var CPUser = (await this.GetAuthenticationStateAsync()).User;
            if (!CPUser.Identity.IsAuthenticated) return null;

            var result = await PasswordSignInAsync(CPUser.Identity.Name, "x", false, false);
            return CPUser;
        }

        public async Task<SignInResult> SignOutAsync()
        {
            var principal = new ClaimsPrincipal();
            var identity = new ClaimsIdentity();
            principal = new System.Security.Claims.ClaimsPrincipal(identity);

            this.SetAuthenticationState(Task.FromResult(new AuthenticationState(principal)));
            this.NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
            var authState = await GetAuthenticationStateAsync();
            return SignInResult.Success;
        }
    }

    // Custom comparer for the Claim class
    public  class ClaimComparer : IEqualityComparer<Claim>
    {
        // Claims are equal if their names and product numbers are equal.
        public bool Equals(Claim x, Claim y)
        {
            //Check whether the compared objects reference the same data.
            if (Object.ReferenceEquals(x, y)) return true;

            //Check whether any of the compared objects is null.
            if (Object.ReferenceEquals(x, null) || Object.ReferenceEquals(y, null)) return false;

            // Check if duplicate type but of different value, don't want it.
            if (x.Type == y.Type && x.Value != y.Value)
                return true;
            //Check whether the Claims' properties are equal.
            //return x.Type == y.Type && x.Value == y.Value;
            return x.Type == y.Type;
        }

        public int GetHashCode(Claim claim)
        {
            //Check whether the object is null
            if (Object.ReferenceEquals(claim, null)) return 0;

            //Get hash code for the Name field if it is not null.
            int hashType = claim.Type == null ? 0 : claim.Type.GetHashCode();

            //Get hash code for the Value field.
            //int hashValue = claim.Value.GetHashCode();

            //Calculate the hash code for the product.
            //return hashType ^ hashValue;
            return hashType;
        }
    }

}
