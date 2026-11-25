using System.Windows;
using System.Windows.Controls;
using KryvnixAntivirus.Desktop.ViewModels;

namespace KryvnixAntivirus.Desktop.Views;

public partial class ScanView : UserControl
{
    public ScanView()
    {
        InitializeComponent();
    }

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_Drop(object sender, DragEventArgs e)
    {
        if (DataContext is ScanViewModel vm && e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            if (e.Data.GetData(DataFormats.FileDrop) is string[] paths)
            {
                foreach (var p in paths)
                {
                    vm.AddTargetPath(p);
                }
            }
        }
    }
}
