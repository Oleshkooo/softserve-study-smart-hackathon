
/**
 * Abstract Class Animal.
 *
 * @class Animal
 */

class BaseValidation{
    isValid = true;

    checkValue(string,predicate,field){
        if(!string) return false;
        if(!predicate)  return false;

    }

    valuesIsValid(){
        return this.isValid;
    }
}