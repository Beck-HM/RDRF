using RDRF.App.ViewModels;
using Xunit;

namespace RDRF.App.Tests;

public class RelayCommandTests
{
    [Fact]
    public void Execute_InvokesAction()
    {
        bool executed = false;
        var cmd = new RelayCommand(_ => executed = true);
        cmd.Execute(null);
        Assert.True(executed);
    }

    [Fact]
    public void CanExecute_Default_ReturnsTrue()
    {
        var cmd = new RelayCommand(_ => { });
        Assert.True(cmd.CanExecute(null));
    }

    [Fact]
    public void CanExecute_WithFunc_ReturnsCorrectly()
    {
        var cmd = new RelayCommand(_ => { }, _ => false);
        Assert.False(cmd.CanExecute(null));
    }

    [Fact]
    public void RaiseCanExecuteChanged_FiresEvent()
    {
        bool fired = false;
        var cmd = new RelayCommand(_ => { });
        cmd.CanExecuteChanged += (_, _) => fired = true;
        cmd.RaiseCanExecuteChanged();
        Assert.True(fired);
    }

    [Fact]
    public void Execute_ParameterlessAction_Works()
    {
        bool executed = false;
        var cmd = new RelayCommand(() => executed = true);
        cmd.Execute(null);
        Assert.True(executed);
    }
}
