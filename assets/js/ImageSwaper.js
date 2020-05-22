(function ($) {
		var MainImage = $('.MainImage');
		$('.ImageSwap').click(function(e){
			MainImage.trigger('zoom.destroy');
			MainImage.attr('src',$(e.currentTarget).attr('src'));
			MainImage

				.parent()
				.zoom();
		})
		MainImage

			.parent()
			.zoom();
	}
)(jQuery);
