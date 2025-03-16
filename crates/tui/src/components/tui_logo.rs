use ratatui::{style::Color, symbols, widgets::{canvas::{Canvas, Line, Map, MapResolution, Rectangle}, Block, Widget}};

pub fn get_tui_logo() -> impl Widget {
    Canvas::default()
    .x_bounds([-90.0, 90.0])
    .y_bounds([-90.0, 90.0])
    .background_color(Color::Blue)
    .marker(symbols::Marker::Block)
    .paint(|ctx| {
        // ctx.draw(&Rectangle {
        //     x: -80.0,
        //     y: -80.0,
        //     width: 160.0,
        //     height: 160.0,
        //     color: Color::Red,
        // });
        let mut i = -70f64;
        while i < 70f64 {
            ctx.draw(&Rectangle {
                x: -70f64,
                y: i,
                width: 140f64,
                height: 1f64,
                color: Color::White
            });
            i = i + 1f64;
        }
        ctx.draw(&Rectangle {
            x: -60f64,
            y: -78f64,
            width: 8f64,
            height: 8f64,
            color: Color::White
        });
    })
}