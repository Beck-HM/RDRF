using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace RDRF.App.Controls
{
    public partial class WaterRippleCanvas : UserControl
    {
        private const int MaxRipples = 8;
        private const double RippleMaxRadius = 80;
        private const double RippleDuration = 0.8;
        private const double RippleStrokeThickness = 1.5;

        // Subtle purple accent color for ripples
        private static readonly Color RippleColor = Color.FromArgb(30, 124, 107, 242);

        public WaterRippleCanvas()
        {
            InitializeComponent();
        }

        private void Canvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            var pos = e.GetPosition(RippleCanvas);
            CreateRipple(pos.X, pos.Y);

            // Limit total ripples for performance
            while (RippleCanvas.Children.Count > MaxRipples)
            {
                RippleCanvas.Children.RemoveAt(0);
            }
        }

        private void CreateRipple(double x, double y)
        {
            // Outer ring
            var ring = new Ellipse
            {
                Width = 0,
                Height = 0,
                Stroke = new SolidColorBrush(RippleColor),
                StrokeThickness = RippleStrokeThickness,
                Fill = Brushes.Transparent,
                IsHitTestVisible = false
            };

            // Offset by half radius so the center of the ripple is at the click point
            Canvas.SetLeft(ring, x - RippleMaxRadius);
            Canvas.SetTop(ring, y - RippleMaxRadius);
            Canvas.SetZIndex(ring, 0);
            RippleCanvas.Children.Add(ring);

            // Animate radius
            var radiusAnim = new DoubleAnimation
            {
                From = 0,
                To = RippleMaxRadius,
                Duration = TimeSpan.FromSeconds(RippleDuration),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };

            // Animate opacity (fade out)
            var opacityAnim = new DoubleAnimation
            {
                From = 1,
                To = 0,
                Duration = TimeSpan.FromSeconds(RippleDuration),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };

            opacityAnim.Completed += (s, e) =>
            {
                RippleCanvas.Children.Remove(ring);
            };

            ring.BeginAnimation(WidthProperty, radiusAnim);
            ring.BeginAnimation(HeightProperty, radiusAnim);
            ring.BeginAnimation(OpacityProperty, opacityAnim);
        }
    }
}
