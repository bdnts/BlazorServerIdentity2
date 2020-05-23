using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using BlazorServerIdentity2.Components;

namespace BlazorServerIdentity2.Areas.Identity.Pages.Account
{
    public partial class SignUp : ComponentBase
    {
        [Inject] NavigationManager navman { get; set; }
        [Inject] IJSRuntime jsruntime { get; set; }
        [Inject] ILogger<SignUp> _logger { get; set; }
        [Inject] RevalidatingIdentityAuthenticationStateProvider<IdentityUser> _riasp { get; set; }

        [CascadingParameter] public Task<AuthenticationState> AuthenticationStateTask { get; set; }
        [Parameter] public string ReturnUrl { get; set; } = "/";

        public AuthenticationState AuthState { get; set; }
        public ClaimsPrincipal CPUser { get; set; }
        public bool showSignUp { get; set; }
        public bool showConfirmation { get; set; }
        public string EmailConfirmationUrl { get; set; }

        /// <summary>
        /// Made the class local for readability
        /// </summary>
        public class DtoSignUp
        {
            //[Required]
            //[MinLength(6, ErrorMessage = "The {0} must be at least 6 characters")]
            //[StringLength(64, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            //[RegularExpression(@"[^\s]+", ErrorMessage = "Spaces are not permitted.")]
            //[Display(Name = "User Name")]
            //public string UserName { get; set; }

            [Required]
            [MinLength(6, ErrorMessage = "The {0} must be at least 6 characters")]
            [DataType(DataType.EmailAddress)]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            [Required]
            [Display(Name = "Confirm password")]
            [CompareProperty("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        /// <summary>
        /// Sign Up object for new user
        /// </summary>
        private DtoSignUp input { get; set; } = new DtoSignUp();

        /// <summary>
        /// Object to process a dictionary of errors per field and display them on form
        /// </summary>
        public ServerSideValidator serverSideValidator;

        public IdentityUser IdentityUser { get; set; }

        protected override async Task OnInitializedAsync()
        {
            AuthState = await AuthenticationStateTask;
            CPUser = AuthState.User;
            showSignUp = true;
        }

        /// <summary>
        /// Invoked by <EditForm> when submit button is clicked.
        /// </summary>
        /// <returns></returns>
        private async Task ValidSubmit()
        {
            var result = await SignUpUser();
            if (!result) return;
            showSignUp = false;

            EmailConfirmationUrl = await _riasp.GetUrl(IdentityUser, IdentityUser.Id, navman.BaseUri, "SignUpEmailConfirmed");
            showConfirmation = true;
            StateHasChanged();
        }

        private void InvalidSubmit()
        {
            _logger.LogInformation("Invalid Submit");
            return;
        }

        private async Task<bool> SignUpUser()
        {
            try
            {
                // Does the username currently exist?

                var user = await _riasp.FindByNameAsync(input.Email);
                if (user != null)
                { //Already exists
                    serverSideValidator.AddError(input, nameof(input.Email), "Sorry, try another username");
                    return false;
                }

                //Using Email for UserName
                IdentityUser = new IdentityUser(input.Email);

                // Actually writing the user details to database
                var result = await _riasp.CreateAsync(IdentityUser, input.Password);
                if (!result.Succeeded)
                {
                    serverSideValidator.AddError(input, result);
                    return false;
                }

                //Retrieve new user to get full info
                IdentityUser = await _riasp.FindByNameAsync(IdentityUser.UserName);

#if Claims
            //Here is an example of how to add default claims values.  
            //But I haven't tested it, so leaving it commented out for now.
            //Build the base claims set and save
            IList<Claim> claims = new List<Claim>()
            {

                // Intial state all 0
                // SubscriberType 0=Not Chosen, 1=Business, 2=Personal
                new Claim("SubscriberType", "0", ClaimValueTypes.Integer),

                // Have they paid their fee?  True False
                new Claim("IsCurrent", "false", ClaimValueTypes.Boolean),

                // Have they Deleted Account
                new Claim("IsDeleted", "false", ClaimValueTypes.Boolean),

                //Registration state 0=Userid, password, completed 1=SubscriberType selected 2=Information supplied, 3=Subscription Paid
                new Claim("RegistrationState", "0", ClaimValueTypes.Integer),

                // Set them to be a user
                new Claim ("IsUser", "true", ClaimValueTypes.Boolean),

                // Set their Place Id
                new Claim ("UserId", IdentityUser.Id, ClaimValueTypes.String)
            };

            var resultAddClaims = await _userManager.AddClaimsAsync(IdentityUser, claims);
            if (!resultAddClaims.Succeeded)
            {
                _logger.LogError("Code={Code} Description={Description} ", resultAddClaims.Errors.ToList()[0].Code, resultAddClaims.Errors.ToList()[0].Description);
                return;
            }
            // SignIn not possible until email confirmed.  Just update Registration Status
            int newRState = 1;
            var claimUpdateResult = await _riasp.UpdateClaimInt(IdentityUser, "RegistrationState", newRState);
            if (!claimUpdateResult.Succeeded)
            {
                CloseAll();
            }
            CloseAll();
#endif
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("Internal Error {message}", ex.Message);
                throw ex;
            }
        }
    }

}
