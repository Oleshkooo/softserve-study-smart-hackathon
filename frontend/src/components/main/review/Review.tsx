import classes from "./Review.module.css";
import {useContext, useEffect, useState} from "react";
import {contextDb} from "../Main"
import {Rating} from "react-simple-star-rating";

function Review() {
    const DataCtx = useContext(contextDb);
    const [rating, setRating] = useState<number>(0);
    const [hover, setHover] = useState<number>(0);

    function handleSubmit(e) {
        e.preventDefault();

        console.log(hover)
    }

    return (
        <div className={classes.container} onSubmit={handleSubmit}>
            <h3>Оцінка завдання<br/> "{DataCtx?.selectedLab.name}"</h3>
            <form className={classes.form} onSubmit={handleSubmit}>
                <span>
                    {[...Array(5)].map((star, index) => {
                        index += 1;
                        return (
                            <button
                                type="button"
                                key={index}
                                className={`${classes.star} ${index <= (hover || rating) ? classes.on : classes.off}`}
                                onClick={() => setRating(index)}
                                onMouseEnter={() => setHover(index)}
                                onMouseLeave={() => setHover(rating)}
                            >
                                <span>&#9733;</span>
                            </button>
                        );
                    })}
                </span>
                <input type={"text"} placeholder={'Ваш коментар...'} required/>
                <button className={classes.button} type={"submit"}>Надіслати</button>
            </form>
        </div>
    )
}

export default Review;