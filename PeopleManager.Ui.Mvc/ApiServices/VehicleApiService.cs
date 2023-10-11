using PeopleManager.Dto.Requests;
using PeopleManager.Dto.Results;
using PeopleManager.Ui.Mvc.ApiServices.Extensions;
using PeopleManager.Ui.Mvc.Stores;
using Vives.Services.Model;

namespace PeopleManager.Ui.Mvc.ApiServices
{
    public class VehicleApiService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly TokenStore _tokenStore;

        public VehicleApiService(IHttpClientFactory httpClientFactory,
            TokenStore tokenStore)
        {
            _httpClientFactory = httpClientFactory;
            _tokenStore = tokenStore;
        }

        public async Task<IList<VehicleResult>> Find()
        {
            var httpClient = _httpClientFactory.CreateClient("PeopleManagerApi");
            httpClient.AddAuthorization(_tokenStore.GetToken());

            var route = "/api/vehicles";
            var httpResponse = await httpClient.GetAsync(route);

            httpResponse.EnsureSuccessStatusCode();

            var vehicles = await httpResponse.Content.ReadFromJsonAsync<IList<VehicleResult>>();

            return vehicles ?? new List<VehicleResult>();
        }

        public async Task<VehicleResult?> Get(int id)
        {
            var httpClient = _httpClientFactory.CreateClient("PeopleManagerApi");
            httpClient.AddAuthorization(_tokenStore.GetToken());
            var route = $"/api/vehicles/{id}";
            var httpResponse = await httpClient.GetAsync(route);

            httpResponse.EnsureSuccessStatusCode();

            return await httpResponse.Content.ReadFromJsonAsync<VehicleResult>();
        }

        public async Task<ServiceResult<VehicleResult?>> Create(VehicleRequest vehicle)
        {
            var httpClient = _httpClientFactory.CreateClient("PeopleManagerApi");
            httpClient.AddAuthorization(_tokenStore.GetToken());
            var route = "/api/vehicles";
            var httpResponse = await httpClient.PostAsJsonAsync(route, vehicle);

            httpResponse.EnsureSuccessStatusCode();

            var serviceResult = await httpResponse.Content.ReadFromJsonAsync<ServiceResult<VehicleResult?>>();
            if (serviceResult is null)
            {
                return new ServiceResult<VehicleResult?>().ApiError();
            }
            return serviceResult;
        }

        public async Task<ServiceResult<VehicleResult?>> Update(int id, VehicleRequest vehicle)
        {
            var httpClient = _httpClientFactory.CreateClient("PeopleManagerApi");
            httpClient.AddAuthorization(_tokenStore.GetToken());
            var route = $"/api/vehicles/{id}";
            var httpResponse = await httpClient.PutAsJsonAsync(route, vehicle);

            httpResponse.EnsureSuccessStatusCode();

            var serviceResult = await httpResponse.Content.ReadFromJsonAsync<ServiceResult<VehicleResult?>>();
            if (serviceResult is null)
            {
                return new ServiceResult<VehicleResult?>().ApiError();
            }
            return serviceResult;
        }

        public async Task<ServiceResult> Delete(int id)
        {
            var httpClient = _httpClientFactory.CreateClient("PeopleManagerApi");
            httpClient.AddAuthorization(_tokenStore.GetToken());
            var route = $"/api/vehicles/{id}";
            var httpResponse = await httpClient.DeleteAsync(route);

            httpResponse.EnsureSuccessStatusCode();

            var serviceResult = await httpResponse.Content.ReadFromJsonAsync<ServiceResult>();
            if (serviceResult is null)
            {
                return new ServiceResult().ApiError();
            }
            return serviceResult;
        }
    }
}
