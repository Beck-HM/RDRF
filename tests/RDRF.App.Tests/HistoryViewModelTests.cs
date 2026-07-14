using RDRF.App.ViewModels;
using Xunit;

namespace RDRF.App.Tests;

public class HistoryViewModelTests
{
    private readonly HistoryViewModel _vm = new();

    [Fact]
    public void BrowseBackupCommand_CanExecute_True()
    {
        Assert.True(_vm.BrowseBackupCommand.CanExecute(null));
    }

    [Fact]
    public void BrowseIncrementalCommand_CanExecute_True()
    {
        Assert.True(_vm.BrowseIncrementalCommand.CanExecute(null));
    }

    [Fact]
    public void ApplyIncrementalCommand_CanExecute_DefaultFalse()
    {
        Assert.False(_vm.ApplyIncrementalCommand.CanExecute(null));
    }

    [Fact]
    public void IsLoading_DefaultsFalse()
    {
        Assert.False(_vm.IsLoading);
    }

}
