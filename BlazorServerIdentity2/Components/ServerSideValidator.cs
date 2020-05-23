using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Identity;

namespace BlazorServerIdentity2.Components
{
    /// <summary>
    /// General purpose EditForm validator.
    /// This will display error messages when the form elements have error, and can also be used after a ValidSubmit() 
    /// to post messages about the form.  For example, during SignIn if the UserName is not found, this can post a message.
    /// </summary>
    public class ServerSideValidator : ComponentBase
    {
        private ValidationMessageStore _messageStore;

        [CascadingParameter] EditContext CurrentEditContext { get; set; }

        /// <inheritdoc />  
        protected override Task OnParametersSetAsync()
        {
            if (CurrentEditContext == null)
            {
                throw new InvalidOperationException($"{nameof(ServerSideValidator)} requires a cascading " +
                    $"parameter of type {nameof(EditContext)}. For example, you can use {nameof(ServerSideValidator)} " +
                    $"inside an {nameof(EditForm)}.");
            }

            _messageStore = new ValidationMessageStore(CurrentEditContext);
            CurrentEditContext.OnValidationRequested += (s, e) => _messageStore.Clear();
            CurrentEditContext.OnFieldChanged += (s, e) => _messageStore.Clear(e.FieldIdentifier);
            return base.OnParametersSetAsync();
        }

        public void DisplayErrors(Dictionary<string, List<string>> errors)
        {
            foreach (var err in errors)
            {
                _messageStore.Add(CurrentEditContext.Field(err.Key), err.Value);
            }
            CurrentEditContext.NotifyValidationStateChanged();
        }
        public void DisplayErrors()
        {
            CurrentEditContext.NotifyValidationStateChanged();
        }

        public void AddError(FieldIdentifier field, string errMessage)
        {
            _messageStore.Add(field, errMessage);
        }

        /// <summary>
        /// Adds an error message to the message store, and then notifies for display
        /// </summary>
        /// <param name="model"></param>
        /// <param name="fieldName"></param>
        /// <param name="errMessage"></param>
        public void AddError(object model, string fieldName, string errMessage)
        {
            var field = new FieldIdentifier(model, fieldName);
            _messageStore.Add(field, errMessage);
            CurrentEditContext.NotifyValidationStateChanged();
        }

        /// <summary>
        /// Adds an error message to the message store but without notification for display.
        /// This enables adding multiple messages, e.g. from a foreach loop
        /// </summary>
        /// <param name="model"></param>
        /// <param name="fieldName"></param>
        /// <param name="errMessage"></param>
        public void AddErrorNoNotify(object model, string fieldName, string errMessage)
        {
            var field = new FieldIdentifier(model, fieldName);
            _messageStore.Add(field, errMessage);
        }

        /// <summary>
        /// IdentityResult messages are returned by most UserManager calls.  
        /// This routine checks for keywords, and if it finds them, generates messages for that field.
        /// This way you can just drop in IdentityResult errors and they will be processed.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="result"></param>
        public void AddError(object model, IdentityResult result)
        {
            foreach (IdentityError idr in result.Errors)
            {
                string field = string.Empty;
                if (idr.Code.Contains("Password")) field = "Password";
                if (idr.Code.Contains("Username")) field = "Username";
                AddError(model, field, idr.Description);
            }
        }
    }
}
