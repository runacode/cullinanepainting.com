<div id="stamped-reviews flexlid">

    <!--Start Stamped.io Auto Installation-->
    <div id="stamped-main-widget" class="stamped-main-widget" data-widget-style="standard">
        <div class="stamped-container" data-count="7" data-widget-style="standard">
            <h2 class="stamped-header-title"><?= T('Reviews'); ?></h2>
            <div class="stamped-header">
                <span itemprop="aggregateRating" itemscope itemtype="http://schema.org/AggregateRating"> <meta
                            itemprop="bestRating" content="5"><meta itemprop="ratingValue" content="4.9"> <meta
                            itemprop="reviewCount" content="7"><meta itemprop="itemreviewed"
                                                                     content="ShoeLove Shoe Cleaning Kit"> </span>
                <div class="stamped-summary" data-count="7">
                    <div style="width:200px;" class="summary-overview">
            <span class="stamped-starrating stamped-summary-starrating">
              <i class="stamped-fa stamped-fa-star"></i>
              <i class="stamped-fa stamped-fa-star"></i>
              <i class="stamped-fa stamped-fa-star"></i>
              <i class="stamped-fa stamped-fa-star"></i>
              <i class="stamped-fa stamped-fa-star-half-o"></i>

              <span class="stamped-summary-caption">
                <span class="stamped-summary-text-2" data-count="66" data-rating="4.6" style="display:none;">4.6</span>
                <span class="stamped-summary-text" data-count="66"
                      data-rating="5"><?= T('Based on 18 reviews'); ?></span>
              </span>
            </span>
                    </div>
                    <div class="stamped-summary-ratings" data-count="66">
                        <div class="summary-rating">
                            <div class="summary-rating-title">5 ★</div>
                            <div class="summary-rating-bar" data-rating="5">
                                <div class="summary-rating-bar-content" style="width:45%;" data-rating="45">45%
                                </div>
                            </div>
                            <div class="summary-rating-count">8</div>
                        </div>
                        <div class="summary-rating">
                            <div class="summary-rating-title">4 ★</div>
                            <div class="summary-rating-bar" data-rating="4">
                                <div class="summary-rating-bar-content" style="width:55%;" data-rating="55">55%
                                </div>
                            </div>
                            <div class="summary-rating-count">10</div>
                        </div>
                        <div class="summary-rating">
                            <div class="summary-rating-title">3 ★</div>
                            <div class="summary-rating-bar" data-rating="3">
                                <div class="summary-rating-bar-content" style="width:0%;" data-rating="0">0%</div>
                            </div>
                            <div class="summary-rating-count">0</div>
                        </div>
                        <div class="summary-rating">
                            <div class="summary-rating-title">2 ★</div>
                            <div class="summary-rating-bar" data-rating="2">
                                <div class="summary-rating-bar-content" style="width:0%;" data-rating="0">0%
                                </div>
                            </div>
                            <div class="summary-rating-count">0</div>
                        </div>
                        <div class="summary-rating">
                            <div class="summary-rating-title">1 ★</div>
                            <div class="summary-rating-bar" data-rating="1">
                                <div class="summary-rating-bar-content" style="width:0%;" data-rating="0">0%
                                </div>
                            </div>
                            <div class="summary-rating-count">0</div>
                        </div>
                    </div>
                    <div class="stamped-summary-photos stamped-summary-photos-container" style="display:none;">
                        <div class="stamped-photos-title"><?= T('Customer Photos'); ?></div>
                        <div style="position:relative;overflow: hidden;">
                            <div class="stamped-photos-carousel" data-total="0">
                                <div></div>
                            </div>
                        </div>
                        <div class="stamped-photos-carousel-btn-left">
                            <span class="btn-slide-left" data-direction="left"><i class="fa fa-chevron-left"></i></span>
                        </div>
                        <div class="stamped-photos-carousel-btn-right">
                            <span class="btn-slide-right" data-direction="right"><i
                                        class="fa fa-chevron-right"></i></span>
                        </div>
                    </div>

                    <span class="stamped-summary-actions">
            <a href="#" class="stamped-summary-actions-newreview"><?= T('Write a Review'); ?></a>

          </span>

                </div>
            </div>
            <div class="stamped-content">
                <div class="stamped-tab-container">
                    <ul class="stamped-tabs">
                        <li id="tab-reviews" class="active" data-type="reviews"
                            data-count="18"><?= T('Reviews'); ?></li>

                    </ul>
                </div>

                <form method="post" id="new-review-form" class="new-review-form"
                      onsubmit="event.preventDefault(); submitForm(this);" style="display:none;">


                    <input type="hidden" name="productId" value="1594183745600">
                    <h3 class="stamped-form-title"></h3>
                    <fieldset class="stamped-form-contact">
                        <div class="stamped-form-contact-name">
                            <label class="stamped-form-label" for="review_author"><?= T('Name'); ?></label>
                            <input class="stamped-form-input stamped-form-input-text " id="review_author" type="text"
                                   name="author" required value placeholder="<?= T('Enter your name'); ?>"
                                   autocomplete="name">
                        </div>
                        <div class="stamped-form-contact-email">
                            <label class="stamped-form-label" for="review_email"><?= T('E-mail'); ?></label>
                            <input class="stamped-form-input stamped-form-input-email " id="review_email" type="email"
                                   name="email" required value placeholder="john.smith@example.com"
                                   autocomplete="email">
                        </div>
                        <div class="stamped-form-contact-location">
                            <label class="stamped-form-label" for="review_location"><?= T('Yes'); ?></label>
                            <input class="stamped-form-input stamped-form-input-text " id="review_location" type="text"
                                   name="location" value placeholder="e.g Paris, France"
                                   autocomplete="shipping country">
                        </div>
                    </fieldset>
                    <fieldset class="stamped-form-review">
                        <div class="stamped-form-review-rating">
                            <label class="stamped-form-label" for="reviewRating"><?= T('Review'); ?></label>
                            <input type="text" id="reviewRating" name="reviewRating"
                                   style="font-size: 0px; border: none; height: 1px; width: 1px; margin: 0; padding: 0; line-height: 0px; min-height: 0px;"
                                   required>

                            <div class="stamped-form-input stamped-starrating">
                                <a href="#" onclick="setRating(this);return false;" class="stamped-fa stamped-fa-star-o"
                                   data-value="1"><span style="display:none;">1</span></a>
                                <a href="#" onclick="setRating(this);return false;" class="stamped-fa stamped-fa-star-o"
                                   data-value="2"><span style="display:none;">2</span></a>
                                <a href="#" onclick="setRating(this);return false;" class="stamped-fa stamped-fa-star-o"
                                   data-value="3"><span style="display:none;">3</span></a>
                                <a href="#" onclick="setRating(this);return false;" class="stamped-fa stamped-fa-star-o"
                                   data-value="4"><span style="display:none;">4</span></a>
                                <a href="#" onclick="setRating(this);return false;" class="stamped-fa stamped-fa-star-o"
                                   data-value="5"><span style="display:none;">5</span></a>
                            </div>
                        </div>
                        <div class="stamped-form-review-title">
                            <label class="stamped-form-label" for="review_title"><?= T('Title'); ?></label>
                            <input class="stamped-form-input stamped-form-input-text" id="review_title" type="text"
                                   name="reviewTitle" required value
                                   placeholder="<?= T('Give your review a title'); ?>">
                        </div>
                        <div class="stamped-form-review-body">
                            <label class="stamped-form-label" for="review_body"><?= T('Review'); ?></label>
                            <div class="stamped-form-input">
                                <textarea class="stamped-form-input stamped-form-input-textarea" id="review_body"
                                          data-product-id="1594183745600" name="reviewMessage" required rows="10"
                                          maxlength="5000"></textarea>
                            </div>
                        </div>
                    </fieldset>
                    <fieldset class="stamped-form-custom-questions">

                    </fieldset>
                    <fieldset class="stamped-form-actions">
    <span class="stamped-file-holder">

    </span>
                        <span class="stamped-file-uploader" style="display:none;">
   <label for="stamped-file-uploader-input">
    <span style="display:none;"><?= T('Upload'); ?></span>
    <input id="stamped-file-uploader-input" type="file" name="stamped-file-uploader-input"
           class="stamped-file-uploader-input" multiple data-product-id="1594183745600" style="display:none;">

            <span class="stamped-file-uploader-btn"
                  style="border:1px solid #333;padding: 6px 10px; font-size:13px; border-radius: .3em;">
                <i class="fa fa-camera"></i>
                <span class="stamped-file-uploader-btn-label2"></span>
            </span>
        </label>
    </span>
                        <span class="stamped-file-loading hide" style="display:none;">
        <i class="fa fa-spinner fa-spin"></i>
    </span>

                        <input id="stamped-button-submit" type="submit"
                               class="stamped-button stamped-button-primary button button-primary btn btn-primary"
                               value="Send">
                    </fieldset>
                </form>
                <div class="stamped-messages">
                    <div class="stamped-thank-you"><h3><?= T('Thanks for submitting your review!'); ?></h3></div>
                </div>
                <div class="stamped-reviews-filter" id="stamped-reviews-filter" data-show-filters>


                    <div class="stamped-reviews-filter-label"></div>

                    <div class="stamped-reviews-search-text" style="display:none;">
                        <span class="stamped-reviews-search-icon stamped-fa stamped-fa-search"></span>
                        <input class="stamped-reviews-search-input" type="text" placeholder="Search reviews">
                        <span class="stamped-reviews-search-clear" style="display:none;">×</span>
                    </div>

                    <div class="stamped-summary-keywords">
                        <ul class="stamped-summary-keywords-list">

                        </ul>
                    </div>

                    <div class="stamped-filter-selects">

                    </div>

                    <div class="stamped-summary-actions-clear" style="cursor: pointer;display:none;"
                         onclick="StampedFn.filterClear();"><?= T('Clear filter'); ?></div>
                </div>
                <?php include 'reviews-data.php' ?>
                <div class="stamped-reviews">

                    <?php $i = 0 ?>
                    <?php foreach ($data->Reviews as $r) : ?>
                        <?php if (!($i % 10)) : ?>
                            <div class="stamped-reviews-page <?php echo($i == 0 ? 'active' : ''); ?>">
                        <?php endif; ?>

                        <?php preg_match("/^(([A-Z]+).*([A-Z]+))/", $r->name, $matches) ?>
                        <?php include 'stamped-review-item.php' ?>

                        <?php if (!($i % 10)) : ?>
                            </div>
                        <?php endif; ?>
                    <?php endforeach; ?>

                    <ul class="stamped-pagination">
                        <li class="page active"><a data-page="1" onclick="switchReviewsPage('1', this)">1</a></li>
                        <li class="page"><a data-page="2" onclick="switchReviewsPage('2', this)">2</a></li>

                    </ul>

                </div>
                <div class="stamped-questions" style="display:none;"></div>
            </div>
        </div>
    </div><!--End Stamped.io Auto Installation-->

    <script>
        if (typeof processReview !== "function") {
            function processReview(form) {
                /*console.log('processReview invoked');
                    console.log('form:');*/
                console.log(form);
                $form = $(form);
                /*console.log('$form:');
                    console.log($form);*/
                $container = $form.closest('.stamped-container');
                /*console.log('$container:');
                    console.log($container);*/
                $btn = $('.stamped-summary-actions-newreview', $container);
                /*console.log('$btn:');
                    console.log($btn);*/
                $msg_wrap = $('.stamped-messages', $form.closest('.stamped-container'));
                $msg = $('.stamped-thank-you', $msg_wrap);
                /*console.log('$msg_wrap:');
                    console.log($msg_wrap);
                    console.log('$msg:');
                    console.log($msg);
              */
                $btn.hide();
                $form.hide();
                $msg_wrap.show();
                $msg.show();
            }
        }
        if (typeof submitForm !== "function") {
            function submitForm(form) {
                $submit = $('#stamped-button-submit', form);
                $submit.attr('disabled', 'disabled');

                setTimeout(function () {
                    processReview(form);
                }, 2000);

            }
        }
        if (typeof setRating !== "function") {
            function setRating(self) {
                var form, parent, val, r, s;
                form = $(self).parents(".new-review-form"),
                    val = $(self).attr("data-value"),
                    parent = $(self).parent(),
                    form.find("input[name='reviewRating']").val(val),
                    r = val,
                    (s = parent).find("a:lt(" + r + ")").removeClass("fa-star-o").addClass("fa-star-checked"),
                    s.find("a:gt(" + (r - 1) + ")").removeClass("fa-star-checked").addClass("fa-star-o");
            }
        }
        if (typeof switchReviewsPage !== "function") {
            function switchReviewsPage(page, self) {
                var $reviewsContainer = $(self).closest('.stamped-reviews');
                var $activePage = $reviewsContainer.find('.stamped-reviews-page.active');
                console.log('-------$activePage', $activePage, $reviewsPages);
                var $reviewsPages = $reviewsContainer.find('.stamped-reviews-page');
                var $pagesLinks = $reviewsContainer.find('.stamped-pagination .page');


                $pagesLinks.removeClass('active');
                $(self).closest('.page').addClass('active');
                $activePage.animate({opacity: 0.3}, 300, function () {
                    setTimeout(function () {
                        $activePage.removeClass('active');
                        $activePage.css({'opacity': 1});
                        $reviewsPages.eq(page - 1).addClass('active');
                    }, 1000);
                });

            }
        }

        if (typeof waitForjQueryAndRun !== "function") {
            function waitForjQueryAndRun() {
                if (!window.jQuery) {
                    console.log('jQuery is not initialized. Waiting 1 sec...');
                    setTimeout(waitForjQueryAndRun, 1000);
                    return false;
                }

                /* Code to execute */

                // Sort reviews by date
                function sortReviewsByDateDescending(a, b) {
                    var date1 = $(a).find(".created").text();
                    date1 = date1.split('/');
                    date1 = new Date(date1[2], date1[1] - 1, date1[0]);
                    var date2 = $(b).find(".created").text();
                    date2 = date2.split('/');
                    date2 = new Date(date2[2], date2[1] - 1, date2[0]);

                    return date1 < date2 ? 1 : -1;
                };

                function initSortReviews() {

                }


                var $reviews_containers = $('.stamped-reviews').each(function () {
                    var $reviews_container = $(this);
                    var $reviews_sorted = $reviews_container.find('.stamped-review').sort(sortReviewsByDateDescending);
                    var $review_pages = $reviews_container.find('.stamped-reviews-page');

                    $review_pages.each(function (index) {
                        $self = $(this);
                        $self.empty();

                        for (var i = 0; i < 10; i++) {
                            if ($reviews_sorted.length > i + index * 10) {
                                $self.append($reviews_sorted.eq(i + index * 10));
                            }
                        }

                    });
                });


                // Toggle new review form
                $('.stamped-summary-actions-newreview').click(function (evt) {
                    evt.stopPropagation();
                    evt.preventDefault();

                    // console.log('.stamped-summary-actions-newreview clicked!');
                    var $review_form = $('#new-review-form', $(evt.target).closest('.stamped-container'));
                    $review_form.toggle();
                });

                // Handle reviews usefulness
                $('a.stamped-thumbs-up, a.stamped-thumbs-down').click(function (evt) {

                    var $elm = $(this).find('i.fa');
                    var $holder = $elm.closest('.stamped-rating-holder');
                    var $number = parseInt($elm.html().replace(/&nbsp;/g, ''));

                    $holder.animate({opacity: 0.3}, 300).delay(1000).animate({opacity: 1}, 300, function () {
                        if ($holder.data('changed') !== 'true') {
                            $number++;
                            $elm.html('&nbsp;' + $number);
                            $holder.data('changed', 'true');
                        }
                    });
                    /*$number.delay(1000).fadeTo(300, 1);*/


                });


            }

            waitForjQueryAndRun();
        }

    </script>

</div>