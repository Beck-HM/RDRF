using RDRF.App.ViewModels;
using Xunit;

namespace RDRF.App.Tests;

public class SettingsViewModelTests
{
    [Fact]
    public void DefaultOutputPath_HasDefault()
    {
        var vm = new SettingsViewModel();
        Assert.Equal("./backup", vm.DefaultOutputPath);
    }

    [Fact]
    public void CloseExit_DefaultsToTrue()
    {
        var vm = new SettingsViewModel();
        Assert.True(vm.CloseExit);
        Assert.False(vm.CloseTray);
    }

    [Fact]
    public void SettingCloseExit_False_DoesNotChangeCloseTray()
    {
        var vm = new SettingsViewModel();
        vm.CloseExit = false;
        Assert.False(vm.CloseTray);
    }

    [Fact]
    public void SettingCloseTray_True_DoesNotChangeCloseExit()
    {
        var vm = new SettingsViewModel();
        vm.CloseTray = true;
        Assert.True(vm.CloseExit);
    }

    [Fact]
    public void SaveCommand_DoesNotThrow()
    {
        var vm = new SettingsViewModel();
        vm.Initialize("./config");
        var ex = Record.Exception(() => vm.SaveCommand.Execute(null));
        Assert.Null(ex);
    }

    [Fact(Skip = "Requires UI thread for FolderBrowserDialog.ShowDialog()")]
    public void BrowseOutputCommand_DoesNotThrowWithNull()
    {
        var vm = new SettingsViewModel();
        var ex = Record.Exception(() => vm.BrowseOutputCommand.Execute(null));
        Assert.Null(ex);
    }

    [Fact]
    public void Initialize_DoesNotThrow()
    {
        var vm = new SettingsViewModel();
        var ex = Record.Exception(() => vm.Initialize("./config"));
        Assert.Null(ex);
    }
}
