using EPiServer.Core;

namespace Swapcode.AlloyWeb.Models.Pages
{
    public interface IHasRelatedContent
    {
        ContentArea RelatedContentArea { get; }
    }
}
