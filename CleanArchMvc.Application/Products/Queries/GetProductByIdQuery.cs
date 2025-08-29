using CleanArchMvc.Domain.Entities;
using MediatR;

namespace CleanArchMvc.Application.Products.Queries
{
    public class GetProductByIdQuery : IRequest<Product>
    {
        public GetProductByIdQuery(int id)
        {
            Id = id;
        }

        public int Id { get; set; }
    }
}
