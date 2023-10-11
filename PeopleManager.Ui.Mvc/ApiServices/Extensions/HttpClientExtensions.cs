namespace PeopleManager.Ui.Mvc.ApiServices.Extensions
{
    public static class HttpClientExtensions
    {
        public static HttpClient AddAuthorization(this HttpClient client, string? token)
        {
            var headerName = "Authorization";
            if (client.DefaultRequestHeaders.Contains(headerName))
            {
                client.DefaultRequestHeaders.Remove(headerName);
            }

            if (!string.IsNullOrWhiteSpace(token))
            {
                client.DefaultRequestHeaders.Add(headerName, $"Bearer {token}");
            }

            return client;
        }
    }
}
